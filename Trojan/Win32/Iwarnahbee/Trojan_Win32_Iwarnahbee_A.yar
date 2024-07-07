
rule Trojan_Win32_Iwarnahbee_A{
	meta:
		description = "Trojan:Win32/Iwarnahbee.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 08 00 00 00 6a 49 8d 45 80 50 ff 15 90 01 02 40 00 6a 20 8d 8d 90 01 02 ff ff 51 ff 15 90 01 02 40 00 6a 57 8d 95 90 01 02 ff ff 52 ff 15 90 01 02 40 00 6a 61 8d 85 90 01 02 ff ff 50 ff 15 90 01 02 40 00 6a 6e 8d 8d 90 01 02 ff ff 51 ff 15 90 01 02 40 00 6a 6e 8d 95 90 01 02 ff ff 52 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}