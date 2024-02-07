
rule Trojan_Win32_Novcod_A{
	meta:
		description = "Trojan:Win32/Novcod.A,SIGNATURE_TYPE_PEHSTR,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 61 74 61 6c 20 45 72 72 6f 72 21 20 20 54 68 65 20 6d 65 64 69 61 20 73 79 73 74 65 6d 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 63 6f 72 72 75 70 74 2e } //01 00  Fatal Error!  The media system on your computer is corrupt.
		$a_01_1 = {57 61 72 6e 69 6e 67 21 20 59 6f 75 72 20 6d 65 64 69 61 20 63 6f 64 65 63 20 69 73 20 6f 75 74 20 6f 66 20 64 61 74 65 2e } //01 00  Warning! Your media codec is out of date.
		$a_01_2 = {2f 70 75 72 63 68 61 73 65 2e 70 68 70 3f 69 64 3d 37 00 } //01 00 
		$a_01_3 = {2f 73 74 79 6b 2e 70 68 70 3f 69 64 3d 37 00 } //01 00 
		$a_01_4 = {57 69 6e 64 6f 77 73 20 63 61 6e 27 74 20 70 6c 61 79 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 6d 65 64 69 61 20 66 6f 72 6d 61 74 73 3a } //01 00  Windows can't play the following media formats:
		$a_01_5 = {41 56 49 3b 41 53 46 3b 57 4d 56 3b 41 56 53 3b 46 4c 56 3b 4d 4b 56 3b 4d 4f 56 3b 33 47 50 3b 4d 50 34 3b 4d 50 47 3b 4d 50 45 47 3b 4d 50 33 3b 41 41 43 3b 57 41 56 3b 57 4d 41 3b 43 44 41 3b 46 4c 41 43 3b 4d 34 41 3b 4d 49 44 2e } //00 00  AVI;ASF;WMV;AVS;FLV;MKV;MOV;3GP;MP4;MPG;MPEG;MP3;AAC;WAV;WMA;CDA;FLAC;M4A;MID.
	condition:
		any of ($a_*)
 
}