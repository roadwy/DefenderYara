
rule Trojan_Win32_Ursnif_SA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3b 4d ac 7f 90 01 01 8b 03 8b 50 0c 8b 70 14 2b d6 8b c1 8d 34 0a 99 f7 ff 8b 45 ec 2b 50 14 8b 40 0c 8a 14 02 8a 06 32 c2 88 06 8b 45 b0 03 c8 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}