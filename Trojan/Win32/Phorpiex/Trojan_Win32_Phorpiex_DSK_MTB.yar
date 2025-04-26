
rule Trojan_Win32_Phorpiex_DSK_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.DSK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {71 65 6d 75 } //1 qemu
		$a_01_1 = {76 69 72 74 75 61 6c } //1 virtual
		$a_01_2 = {76 6d 77 61 72 65 } //1 vmware
		$a_01_3 = {99 b9 1a 00 00 00 f7 f9 83 c2 61 8b 45 f8 03 45 fc 88 10 eb d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}