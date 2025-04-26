
rule Trojan_Win32_Glupteba_UJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.UJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 db 09 cb 31 17 43 81 c3 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 cb 29 db 39 f7 75 ?? 21 db c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}