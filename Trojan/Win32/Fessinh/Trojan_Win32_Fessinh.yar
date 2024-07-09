
rule Trojan_Win32_Fessinh{
	meta:
		description = "Trojan:Win32/Fessinh,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 85 00 ff ff ff 50 e8 ?? ?? f7 ff 85 c0 75 07 c6 85 00 ff ff ff 43 8a 85 00 ff ff ff 50 e8 ?? ?? f7 ff 83 f8 01 1b c0 40 84 c0 75 07 c6 85 00 ff ff ff 43 8d 85 fc fe ff ff 8a 95 00 ff ff ff e8 ?? ?? f7 ff 8b 95 fc fe ff ff 8b c3 b9 ?? ?? ?? 00 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}