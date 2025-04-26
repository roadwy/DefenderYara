
rule Trojan_Win32_StealerC_NN_MTB{
	meta:
		description = "Trojan:Win32/StealerC.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5 89 45 fc 8b 45 08 56 57 33 f6 33 ff 3b de 89 85 ?? ?? ?? ?? 7e 42 83 fb 2d 75 07 56 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}