
rule Trojan_Win32_DllHijack_BJ_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 59 8b 45 08 03 45 fc 0f b6 00 33 45 10 8b 4d 08 03 4d fc 88 01 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}