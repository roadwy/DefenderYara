
rule Trojan_Win32_CobaltStrike_MNO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 f0 88 03 83 45 f0 01 8b 45 b4 39 45 f0 } //2
		$a_01_1 = {44 63 29 29 23 55 2a 4d 48 4d 6e 44 61 24 38 3e 2b 23 50 } //1 Dc))#U*MHMnDa$8>+#P
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}