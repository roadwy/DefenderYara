
rule Trojan_Win32_SmokeLoader_ASGH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 ff fe d0 00 00 7d 07 56 ff 15 ?? ?? ?? 00 56 ff 15 ?? ?? ?? 00 56 ff 15 ?? ?? ?? 00 56 56 ff 15 ?? ?? ?? 00 81 ff ee 37 3a 00 7f 09 47 81 ff 2f e5 00 00 7c } //3
		$a_01_1 = {81 ff ee 37 3a 00 7f 09 47 81 ff 2f e5 00 00 7c } //1
		$a_01_2 = {81 ff 85 ed 8c 05 7f 09 47 81 ff b1 02 65 1f 7c } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}