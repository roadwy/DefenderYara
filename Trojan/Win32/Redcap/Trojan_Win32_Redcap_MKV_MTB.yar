
rule Trojan_Win32_Redcap_MKV_MTB{
	meta:
		description = "Trojan:Win32/Redcap.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ea d4 7f 00 00 81 ea 37 bd 00 00 e8 0a 00 00 00 00 4c 40 ?? 4f 34 3a 32 46 35 83 c4 04 81 e2 5d 1d 01 00 5a 56 56 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}