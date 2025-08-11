
rule Trojan_Win64_ShellcodeRunner_MLD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 c0 48 98 0f b6 44 05 a0 88 85 fe 10 00 00 48 8d 95 d0 08 00 00 48 8b 85 ?? 11 00 00 48 01 d0 0f b6 00 32 85 fe 10 00 00 48 8d 8d a0 00 00 00 48 8b 95 ?? 11 00 00 48 01 ca 88 02 48 83 85 ?? 11 00 00 01 48 81 bd 38 11 00 00 1f 08 00 00 0f 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}