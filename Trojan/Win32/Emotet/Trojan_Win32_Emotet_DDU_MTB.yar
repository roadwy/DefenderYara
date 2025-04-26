
rule Trojan_Win32_Emotet_DDU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c8 31 f6 89 55 cc 89 f2 8b 75 cc f7 f6 89 cf 83 e7 03 8b 5d e8 8a 1c 0b 8b 75 d0 83 fe 02 0f 47 fa 2a 1c 3d ?? ?? ?? ?? 01 ce 8b 55 e4 88 1c 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}