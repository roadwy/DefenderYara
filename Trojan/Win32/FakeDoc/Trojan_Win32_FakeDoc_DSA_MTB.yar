
rule Trojan_Win32_FakeDoc_DSA_MTB{
	meta:
		description = "Trojan:Win32/FakeDoc.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 83 e1 03 8a 91 64 fb ?? ?? 8a 8c 06 28 0e ?? ?? 32 ca 88 88 28 0e ?? ?? 75 ?? 88 ?? ?? ?? ?? ?? 40 3b c7 7c } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}