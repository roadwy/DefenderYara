
rule Trojan_Win32_RedLineStealer_GE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 10 85 d2 74 0e 8a 84 15 ?? ?? ?? ?? 30 44 17 ff 4a 75 f2 } //10
		$a_80_1 = {4d 41 4e 54 43 56 53 52 56 58 42 59 47 48 49 42 50 53 40 41 57 44 52 54 2e 43 4f 4d } //MANTCVSRVXBYGHIBPS@AWDRT.COM  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}