
rule TrojanDownloader_O97M_IcedID_AIC_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.AIC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 22 } //1 = "c:\users\public\main.hta"
		$a_01_1 = {2e 65 78 65 63 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 22 } //1 .exec frm.CommandButton1.Tag & " c:\users\public\main.hta"
		$a_01_2 = {43 61 6c 6c 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 Call frm.CommandButton1_Click
		$a_01_3 = {3d 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c 63 32 39 } //1 = "<div id='content'>fTtlc29
		$a_03_4 = {43 6c 6f 73 65 20 23 31 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_5 = {50 72 69 6e 74 20 23 31 2c } //1 Print #1,
		$a_01_6 = {66 6f 72 28 78 3d 30 3b 78 3c 4c 3b 78 2b 2b } //1 for(x=0;x<L;x++
		$a_01_7 = {7a 79 78 77 76 75 74 73 72 71 70 6f 6e 6d 6c 6b 6a 69 68 67 66 65 64 63 62 61 5a 59 58 57 56 55 54 53 52 51 50 4f 4e 4d 4c 4b 4a 49 48 47 46 45 44 43 42 41 } //1 zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA
		$a_01_8 = {73 70 6c 69 74 28 27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 3b } //1 split('').reverse().join('');
		$a_01_9 = {54 69 6d 65 6f 75 74 20 3d 20 36 30 30 30 30 } //1 Timeout = 60000
		$a_01_10 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}