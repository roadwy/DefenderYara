
rule Trojan_Win32_Ghanarava_MCE_MTB{
	meta:
		description = "Trojan:Win32/Ghanarava.MCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {a8 69 42 00 ff f8 78 01 00 ff ff ff 08 00 00 00 01 00 00 00 06 00 00 00 e9 00 00 00 c8 67 42 00 5c 64 42 00 4c 7b 40 00 78 } //2
		$a_01_1 = {4c 61 75 6e 63 68 65 72 20 66 6f 72 20 5a 61 70 72 65 74 00 4c 61 } //1 慌湵档牥映牯娠灡敲t慌
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}