
rule Trojan_Win32_Stealer_DAJ_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 30 0c 03 43 3b 5d fc 0f 82 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}