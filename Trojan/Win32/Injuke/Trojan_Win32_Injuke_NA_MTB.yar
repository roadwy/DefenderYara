
rule Trojan_Win32_Injuke_NA_MTB{
	meta:
		description = "Trojan:Win32/Injuke.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6c 73 74 72 63 61 74 41 00 e8 69 52 ce ?? ?? ?? ?? 65 74 46 75 6c } //5
		$a_01_1 = {69 74 27 73 20 69 6e 66 65 63 74 65 64 20 62 79 20 61 20 56 69 72 75 73 20 6f 72 20 63 72 61 63 6b 65 64 2e 20 54 68 69 73 20 66 69 6c 65 20 77 6f 6e 27 74 20 77 6f 72 6b 20 61 6e 79 6d 6f 72 65 } //1 it's infected by a Virus or cracked. This file won't work anymore
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}