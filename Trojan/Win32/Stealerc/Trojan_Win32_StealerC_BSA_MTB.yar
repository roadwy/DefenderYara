
rule Trojan_Win32_StealerC_BSA_MTB{
	meta:
		description = "Trojan:Win32/StealerC.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d db 04 00 00 75 06 8d 8a 49 9e 00 00 81 f9 cf 0b 00 00 75 0c 89 3d 20 73 45 00 89 35 24 73 45 00 40 3d 56 0b 18 01 7c d7 89 0d 1c 9f 82 00 33 f6 81 fe 77 b7 55 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}