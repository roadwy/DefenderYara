
rule Trojan_Win32_RecordBreaker_EH_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {83 e2 1f 03 c2 c1 f8 05 6b c0 32 83 e0 42 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}