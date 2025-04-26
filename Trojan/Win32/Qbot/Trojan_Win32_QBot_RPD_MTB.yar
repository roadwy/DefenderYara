
rule Trojan_Win32_QBot_RPD_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 68 4b 67 54 52 6b 00 42 6b 74 66 4a 00 43 7a 4e 6b 74 45 00 44 41 4b 6b 45 4d 65 5a 66 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 桁杋剔k歂晴J穃歎䕴䐀䭁䕫敍晚䐀汬敒楧瑳牥敓癲牥
	condition:
		((#a_01_0  & 1)*1) >=1
 
}