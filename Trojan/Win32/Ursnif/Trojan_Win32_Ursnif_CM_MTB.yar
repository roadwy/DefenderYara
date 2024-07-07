
rule Trojan_Win32_Ursnif_CM_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.CM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {a5 a5 a5 8b 4d d0 33 4d d4 68 00 04 00 00 2b 4d fc 03 4d ec 8d 4c 11 ff 8b 55 f8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}