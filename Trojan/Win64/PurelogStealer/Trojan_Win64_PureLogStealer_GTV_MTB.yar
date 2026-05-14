
rule Trojan_Win64_PureLogStealer_GTV_MTB{
	meta:
		description = "Trojan:Win64/PureLogStealer.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 33 37 64 63 30 34 37 65 32 32 38 62 39 39 62 35 30 65 39 34 34 33 30 32 32 } //5 f37dc047e228b99b50e9443022
		$a_01_1 = {64 32 34 62 36 65 34 36 30 62 61 38 34 63 32 32 34 39 33 30 64 61 } //5 d24b6e460ba84c224930da
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}