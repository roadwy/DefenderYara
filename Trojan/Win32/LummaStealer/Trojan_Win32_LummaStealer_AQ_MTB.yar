
rule Trojan_Win32_LummaStealer_AQ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 0c 24 0f b6 4c 0c 08 05 ?? ?? ?? ?? 31 c8 89 44 24 04 8b 44 24 04 04 ?? 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8 08 72 } //4
		$a_01_1 = {81 3c ca 13 f2 8e 14 74 07 41 39 c8 75 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}