
rule Trojan_Win32_Zenpack_MBKI_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MBKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 6e 72 6e 6e 6c 72 73 65 6e 37 36 2e 64 6c 6c 00 54 61 72 65 74 78 6f 70 6e 6e 65 76 6e 4e 74 69 74 78 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //1 湥湲汮獲湥㘷搮汬吀牡瑥潸湰敮湶瑎瑩x敫湲汥㈳匮敬灥
	condition:
		((#a_01_0  & 1)*1) >=1
 
}