
rule Trojan_Win32_KazakageDropper_SCP_MTB{
	meta:
		description = "Trojan:Win32/KazakageDropper.SCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 8c 8e 40 00 e8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 0c 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}