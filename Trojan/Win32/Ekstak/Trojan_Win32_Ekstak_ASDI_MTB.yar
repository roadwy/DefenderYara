
rule Trojan_Win32_Ekstak_ASDI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 53 56 57 6a 14 6a 40 33 db ff 15 [0-04] 8b 74 24 1c 8b f8 39 5e 19 75 } //5
		$a_03_1 = {83 ec 10 53 55 56 57 ff 15 [0-03] 00 6a 14 6a 40 8b f0 32 db ff 15 [0-03] 00 8b f8 8d 44 24 10 50 56 ff 15 [0-03] 00 8b 74 24 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}