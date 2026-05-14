
rule Trojan_Win64_Nodistor_A{
	meta:
		description = "Trojan:Win64/Nodistor.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 72 65 46 69 6c 65 41 70 69 73 41 4e 53 49 ?? ?? ?? 43 6c 6f 73 65 48 61 6e 64 6c 65 90 09 0d 00 5f 90 11 03 00 5f 90 0f 04 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}