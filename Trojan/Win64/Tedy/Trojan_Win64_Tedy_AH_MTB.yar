
rule Trojan_Win64_Tedy_AH_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 db 48 8b 54 24 58 48 83 fa 07 0f 86 c1 00 00 00 48 8b 4c 24 40 48 8d 14 55 02 00 00 00 48 8b c1 48 81 fa 00 10 00 00 0f 82 9f 00 00 00 48 8b 49 f8 } //1
		$a_01_1 = {56 69 78 65 6e 2e 65 78 65 } //1 Vixen.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}