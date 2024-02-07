
rule Trojan_Win32_Phorpiex_DSK_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.DSK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 65 6d 75 } //01 00  qemu
		$a_01_1 = {76 69 72 74 75 61 6c } //01 00  virtual
		$a_01_2 = {76 6d 77 61 72 65 } //01 00  vmware
		$a_01_3 = {99 b9 1a 00 00 00 f7 f9 83 c2 61 8b 45 f8 03 45 fc 88 10 eb d5 } //00 00 
	condition:
		any of ($a_*)
 
}