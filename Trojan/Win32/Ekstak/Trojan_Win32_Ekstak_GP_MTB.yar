
rule Trojan_Win32_Ekstak_GP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ca ae 25 00 e2 ae 25 00 f4 ae 25 00 fe ae 25 00 1a af 25 00 30 af 25 00 4a af 25 00 5a af 25 00 7a af 25 00 88 af 25 00 9e af 25 00 b4 af 25 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}