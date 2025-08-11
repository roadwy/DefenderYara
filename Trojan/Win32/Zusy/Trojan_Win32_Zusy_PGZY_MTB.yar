
rule Trojan_Win32_Zusy_PGZY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 db 74 01 ea 31 ?? ?? ?? 81 c3 04 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}