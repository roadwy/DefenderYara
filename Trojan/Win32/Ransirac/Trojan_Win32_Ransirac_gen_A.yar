
rule Trojan_Win32_Ransirac_gen_A{
	meta:
		description = "Trojan:Win32/Ransirac.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 31 53 53 6a 4e 57 ff 15 90 01 04 53 8d 85 90 01 04 50 6a 08 56 57 ff 15 90 01 04 57 ff 15 90 01 04 56 88 5e 08 ff 15 90 01 04 88 1c 30 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}