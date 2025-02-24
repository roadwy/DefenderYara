
rule Trojan_Win32_Tofsee_KAJ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 31 5f 83 c1 ?? f7 df 83 c7 ?? 8d 7f ?? 83 ef ?? 29 f7 89 fe c7 03 ?? ?? ?? ?? 01 3b 8d 5b ?? 83 ea ?? 81 fa ?? ?? ?? ?? 75 d5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}