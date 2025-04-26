
rule Trojan_Win32_AutoInj_GZN_MTB{
	meta:
		description = "Trojan:Win32/AutoInj.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 19 a8 bf 9d 8c 5b 6c ed f0 34 30 bb b0 63 98 6c ?? ?? 6b 18 95 7c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}