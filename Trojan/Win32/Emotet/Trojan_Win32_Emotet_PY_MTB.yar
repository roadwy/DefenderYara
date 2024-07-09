
rule Trojan_Win32_Emotet_PY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 ae 22 00 00 f7 f9 8d 04 3f 2b d6 03 d5 03 d0 8b 44 24 ?? 8a 0c 02 8b 44 24 ?? 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}