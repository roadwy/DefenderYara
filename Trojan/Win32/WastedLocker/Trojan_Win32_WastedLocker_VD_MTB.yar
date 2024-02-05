
rule Trojan_Win32_WastedLocker_VD_MTB{
	meta:
		description = "Trojan:Win32/WastedLocker.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ff c7 05 90 01 08 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_01_1 = {eb 00 31 0d } //00 00 
	condition:
		any of ($a_*)
 
}