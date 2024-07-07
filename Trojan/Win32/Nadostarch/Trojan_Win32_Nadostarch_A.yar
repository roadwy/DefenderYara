
rule Trojan_Win32_Nadostarch_A{
	meta:
		description = "Trojan:Win32/Nadostarch.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 6f 72 72 6e 61 64 6f 73 2e 72 75 } //1 torrnados.ru
		$a_01_1 = {2f 73 65 6e 64 5f 73 6d 73 5f 32 34 2e 70 68 70 3f 74 65 6c 3d } //1 /send_sms_24.php?tel=
		$a_01_2 = {2f 67 65 74 6f 70 2e 70 68 70 3f 74 65 6c 3d } //1 /getop.php?tel=
		$a_01_3 = {26 61 72 68 69 64 3d } //1 &arhid=
		$a_01_4 = {4b 45 59 20 52 52 52 } //1 KEY RRR
		$a_01_5 = {47 4f 20 52 52 52 } //1 GO RRR
		$a_01_6 = {a5 a4 c7 85 f8 de ff ff 03 35 46 46 c7 85 f8 df ff ff 03 35 46 46 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3) >=6
 
}