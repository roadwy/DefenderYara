
rule Trojan_Win32_Netwire_P_MTB{
	meta:
		description = "Trojan:Win32/Netwire.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 32 c0 5e 8b 8c 24 ?? ?? ?? ?? 33 cc e8 ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? c3 8b ce 8d 51 01 } //1
		$a_01_1 = {90 8a 01 41 84 c0 75 f9 2b ca 8d 79 0a 81 ff 00 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}