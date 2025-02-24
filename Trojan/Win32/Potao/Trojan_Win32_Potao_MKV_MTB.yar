
rule Trojan_Win32_Potao_MKV_MTB{
	meta:
		description = "Trojan:Win32/Potao.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c8 0f b6 4c 11 ff 30 0c 02 8b 73 0c 0f b7 53 ?? 0f b6 0c 06 2b d0 30 4c 32 ff 0f b7 4b 10 8b 53 0c 2b c8 40 0f b6 4c 11 ?? 30 4c 02 ff 0f b7 4b 10 d1 e9 3b c1 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}