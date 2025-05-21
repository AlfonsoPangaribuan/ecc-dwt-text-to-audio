"""
Mean Opinion Score (MOS) evaluation for audio steganography.
"""
import os
import sys
import wave
import numpy as np
import matplotlib.pyplot as plt
import random
import click
from typing import List, Dict, Tuple
import json
import time
from datetime import datetime

# Import local modules if needed
# import dwt_stego


def play_audio(wav_path: str) -> None:
    """
    Play audio file using platform-specific methods.
    
    Args:
        wav_path: Path to WAV file
    """
    try:
        import platform
        system = platform.system()
        
        if system == 'Windows':
            import winsound
            winsound.PlaySound(wav_path, winsound.SND_FILENAME)
        elif system == 'Darwin':  # macOS
            os.system(f"afplay {wav_path}")
        else:  # Linux and others
            try:
                import pygame
                pygame.mixer.init()
                pygame.mixer.music.load(wav_path)
                pygame.mixer.music.play()
                while pygame.mixer.music.get_busy():
                    pygame.time.Clock().tick(10)
            except ImportError:
                os.system(f"aplay {wav_path}")
                
    except Exception as e:
        print(f"Error playing audio: {str(e)}")
        print("Please play the audio file manually.")


def conduct_mos_test(original_wav: str, stego_wav: str, num_listeners: int = 1) -> Dict:
    """
    Conduct a Mean Opinion Score (MOS) test.
    
    Args:
        original_wav: Path to original WAV file
        stego_wav: Path to stego WAV file
        num_listeners: Number of listeners
        
    Returns:
        Dictionary with MOS results
    """
    results = {
        "test_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "original_wav": original_wav,
        "stego_wav": stego_wav,
        "num_listeners": num_listeners,
        "scores": [],
        "average_score": 0.0,
        "comments": []
    }
    
    print("\n=== Mean Opinion Score (MOS) Testing ===")
    print("MOS is a subjective quality measure for audio, rated on a scale of 1-5:")
    print("5 - Excellent: Imperceptible difference from original")
    print("4 - Good: Perceptible but not annoying")
    print("3 - Fair: Slightly annoying")
    print("2 - Poor: Annoying")
    print("1 - Bad: Very annoying")
    
    for i in range(num_listeners):
        print(f"\nListener {i+1}:")
        
        # Randomize order of playback
        play_order = ["original", "stego"] if random.random() > 0.5 else ["stego", "original"]
        
        for audio_type in play_order:
            wav_path = original_wav if audio_type == "original" else stego_wav
            print(f"\nPlaying {audio_type} audio...")
            play_audio(wav_path)
            time.sleep(1)  # Pause between playbacks
        
        # Get score for stego audio
        while True:
            try:
                score = int(input("\nRate the quality of the stego audio (1-5): "))
                if 1 <= score <= 5:
                    break
                else:
                    print("Please enter a number between 1 and 5.")
            except ValueError:
                print("Please enter a valid number.")
        
        comment = input("Any comments about the audio quality? (optional): ")
        
        results["scores"].append(score)
        if comment:
            results["comments"].append(comment)
    
    # Calculate average score
    results["average_score"] = sum(results["scores"]) / len(results["scores"])
    
    print(f"\nMOS Test Results:")
    print(f"Number of listeners: {num_listeners}")
    print(f"Average score: {results['average_score']:.2f}")
    print(f"Individual scores: {results['scores']}")
    if results["comments"]:
        print(f"Comments:")
        for comment in results["comments"]:
            print(f"- {comment}")
    
    # Save results to file
    results_file = "mos_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"\nResults saved to {results_file}")
    
    return results


@click.command()
@click.option('--original-wav', required=True, help='Path to original WAV file')
@click.option('--stego-wav', required=True, help='Path to stego WAV file')
@click.option('--listeners', default=1, help='Number of listeners')
def main(original_wav: str, stego_wav: str, listeners: int):
    """Run MOS evaluation."""
    conduct_mos_test(original_wav, stego_wav, listeners)


if __name__ == '__main__':
    main()
