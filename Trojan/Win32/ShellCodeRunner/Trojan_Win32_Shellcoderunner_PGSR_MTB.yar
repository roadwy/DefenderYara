
rule Trojan_Win32_Shellcoderunner_PGSR_MTB{
	meta:
		description = "Trojan:Win32/Shellcoderunner.PGSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 00 f8 08 41 00 30 22 41 00 18 22 41 00 00 22 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}