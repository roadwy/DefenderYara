
rule Trojan_Win32_FakeAV_NA_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 21 45 f4 81 45 dc } //2
		$a_01_1 = {8b 45 f0 31 45 f4 8b 45 0c 21 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}