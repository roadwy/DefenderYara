
rule Trojan_Win32_Tofsee_DMJ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.DMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 05 03 cd 33 cf 31 4c 24 14 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 14 29 44 24 18 8d 44 24 1c e8 ?? ?? ?? ?? 4b 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}