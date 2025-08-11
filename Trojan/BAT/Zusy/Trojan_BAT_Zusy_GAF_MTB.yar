
rule Trojan_BAT_Zusy_GAF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {4d 54 67 34 4c 6a 49 78 4e 43 34 78 4d 44 63 75 4d 6a 41 3d } //MTg4LjIxNC4xMDcuMjA=  2
		$a_80_1 = {52 32 78 76 59 6d 46 73 58 46 78 58 61 57 35 46 65 48 42 73 62 33 4a 6c 63 6c 4e 35 62 6d 4d 3d } //R2xvYmFsXFxXaW5FeHBsb3JlclN5bmM=  1
		$a_80_2 = {55 32 39 6d 64 48 64 68 63 6d 56 63 58 45 31 70 59 33 4a 76 63 32 39 6d 64 46 78 63 56 32 6c 75 5a 47 39 33 63 31 78 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 58 46 4a 31 62 67 3d 3d } //U29mdHdhcmVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXFJ1bg==  1
		$a_80_3 = {52 58 68 77 62 47 39 79 5a 58 4a 54 5a 58 4a 32 61 57 4e 6c } //RXhwbG9yZXJTZXJ2aWNl  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}