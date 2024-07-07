
rule Ransom_Win32_Criakl_F_bit{
	meta:
		description = "Ransom:Win32/Criakl.F!bit,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8b 84 9d 00 fc ff ff 03 f0 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a c8 8b 84 b5 00 fc ff ff 89 84 9d 00 fc ff ff 0f b6 c1 89 84 b5 00 fc ff ff 8b 8c 9d 00 fc ff ff 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 84 8d 00 fc ff ff 8b 4d 10 30 04 0a 42 3b d7 72 91 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}