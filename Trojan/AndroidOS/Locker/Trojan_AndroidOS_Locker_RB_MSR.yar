
rule Trojan_AndroidOS_Locker_RB_MSR{
	meta:
		description = "Trojan:AndroidOS/Locker.RB!MSR,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {35 23 15 00 48 05 07 03 94 06 04 00 71 10 ?? ?? 06 00 0a 06 48 06 08 06 b7 65 8d 55 4f 05 01 04 d8 04 04 01 d8 03 03 01 28 ec } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}