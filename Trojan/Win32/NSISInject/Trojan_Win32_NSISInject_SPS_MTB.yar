
rule Trojan_Win32_NSISInject_SPS_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 3b 04 6e 34 ed 04 1e 88 04 3b 47 3b 7d f0 72 ee } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}