
rule Trojan_Win32_Kryptik_GS_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.GS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 9b cf a0 f7 8b f8 eb 12 81 fe 53 09 00 00 76 0a 8b c7 2b f7 33 d2 f7 f1 8b fa 33 db 83 fe 35 } //1
		$a_01_1 = {8b de 0f af d8 81 c6 9b 8f 4e 72 89 75 fc 89 5d 08 33 ff 47 b9 9b cf a0 f7 83 fb 41 76 66 85 f6 8b cf 8b c3 0f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}