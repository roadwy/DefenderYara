
rule Trojan_Win32_Delfinject_RWB_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 c7 f0 74 ?? 8b 45 ?? 8b 40 ?? 8b 75 ?? 8b 76 ?? 03 06 66 81 e3 ff 0f 0f b7 db 03 c3 8b 5d ?? 8b 5b ?? 01 18 83 01 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}