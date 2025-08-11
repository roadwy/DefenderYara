
rule Trojan_Win32_KeyLogger_EJQQ_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.EJQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c1 8b 55 08 03 55 fc 88 02 ?? ?? b0 01 8b e5 5d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}