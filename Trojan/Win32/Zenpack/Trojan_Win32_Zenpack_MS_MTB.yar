
rule Trojan_Win32_Zenpack_MS_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {75 08 50 50 ff [0-05] e8 [0-04] 30 [0-03] 81 [0-05] 75 ?? 6a 00 [0-0a] ff [0-05] 46 33 [0-03] 3b [0-03] 90 18 81 } //1
		$a_02_1 = {75 08 50 50 ff 15 [0-04] e8 [0-04] 30 [0-03] 81 ff [0-04] 75 0f 6a 00 8d [0-03] 50 6a 00 ff 15 [0-04] 46 33 [0-03] 3b [0-03] 90 18 81 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}