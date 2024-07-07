
rule Trojan_BAT_Bladabindi_GPD_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_80_0 = {4d 23 67 23 41 23 75 23 41 23 47 23 34 23 41 23 62 23 77 23 41 23 74 23 41 23 47 23 6b 23 41 23 63 23 41 23 41 23 75 23 41 23 47 23 49 23 41 23 61 23 51 23 42 23 36 23 41 23 41 23 41 } //M#g#A#u#A#G#4#A#b#w#A#t#A#G#k#A#c#A#A#u#A#G#I#A#a#Q#B#6#A#A#A  5
		$a_80_1 = {54 23 56 23 71 23 51 23 41 23 41 23 4d 23 41 23 41 23 41 23 41 23 45 23 41 23 41 23 41 23 41 23 } //T#V#q#Q#A#A#M#A#A#A#A#E#A#A#A#A#  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}