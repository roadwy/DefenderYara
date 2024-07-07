
rule Trojan_BAT_Redline_NEH_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 28 43 00 00 0a 25 26 0b 28 90 01 01 00 00 0a 25 26 07 16 07 8e 69 6f 90 01 01 00 00 0a 25 26 0a 28 35 00 00 0a 25 26 06 6f 39 00 00 0a 25 26 0c 90 00 } //1
		$a_01_1 = {64 00 32 00 6c 00 75 00 5a 00 47 00 39 00 33 00 63 00 79 00 35 00 6b 00 5a 00 57 00 4e 00 76 00 5a 00 47 00 56 00 79 00 4c 00 6d 00 31 00 68 00 62 00 6d 00 46 00 6e 00 5a 00 58 00 49 00 75 00 63 00 32 00 39 00 6d 00 64 00 48 00 64 00 68 00 63 00 6d 00 55 00 6c 00 } //1 d2luZG93cy5kZWNvZGVyLm1hbmFnZXIuc29mdHdhcmUl
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}