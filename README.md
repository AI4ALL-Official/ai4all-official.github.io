# Oil Spill Detection

Trained a ResNet50 CNN to detect marine oil spills, implementing data augmentation techniques with Keras/Tensorflow, as part of the AI4ALL Ignite accelerator.

## Problem Statement <!--- do not change this line -->

Oil spills are deterimental to the environment. In the Deepwater Horizon oil spill, the largest oil spill in history, 4.9 million barrels (210 million gallons) of oil were released in the Gulf of Mexico. This oil spill alone is estimated to have killed up to 5 trillion fish, 84 thousand birds, and at least 59 thousand sea turtles (National Oceanic and Atmospheric Administration). 
We believe that computer vision technology can be used to mitigate the damage to wildlife by identifying images of oil spills to help clean up oil spills around the world.

## Key Results <!--- do not change this line -->

1. Used transfer learning to train a ResNet50 CNN on a 300-image dataset to classify oil spill imagery.
2. Utilized image transformations to generate images based on pre-existing ones.
3. Achieved ~86% validation accuracy after training.

## Methodologies <!--- do not change this line -->

To accomplish this, we utilized the Keras ResNet18 model to classify images of water bodies with supervised learning. We designed our model to use image normalization to allow the model to identify patterns more easily. Other techniques we incorporated:

Image augmentation
Freezing layers
Early stopping
Dropout regularization
Differential learning rates: higher LR for new layers, lower for pre-trained

## Data Sources <!--- do not change this line -->

(UPDATE IN README.md)
Include any relevant data sources that were used in your project.

*EXAMPLE:*
*Kaggle Datasets: [Marine Oil Spill Detection](https://www.kaggle.com/datasets/afzalofficial/marine-oil-spill-detection)*

## Technologies Used <!--- do not change this line -->

- *Python*
- *pandas*
- *PyTorch*
- *Matplotlib*
- *NumPy*

## Authors <!--- do not change this line -->

*This project was completed in collaboration with:*
- *Asad Chaudhry([achau024@fiu.edu](mailto:achau024@fiu.edu))*
- *Jason Qin ([jq2406@nyu.edu](mailto:jq2406@nyu.edu))*
- *Xavier Rush ([xcrush@aggies.ncat.edu](xcrush@aggies.ncat.edu))*
