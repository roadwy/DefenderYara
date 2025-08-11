
rule Trojan_Win32_Shellcoderunner_SCRT_MTB{
	meta:
		description = "Trojan:Win32/Shellcoderunner.SCRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5e 5b 8b 4d fc 5f e8 ?? ?? ?? 00 c9 c2 08 00 ff b5 e4 fb ff ff ff 15 ?? ?? ?? 00 57 ff b5 e0 fb ff ff ff 15 ?? ?? ?? 00 53 ff 15 ?? ?? ?? 00 59 33 c0 eb cc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}